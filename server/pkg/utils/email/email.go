// The email package contains functions for directly sending emails.
//
// These functions can be used for directly sending emails to given email
// addresses. This is used for transactional emails, for example OTP requests.
// Currently, we use Zoho Transmail to send out the actual mail.
package email

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/smtp"
	"net/url"
	"path"
	"strings"

	"github.com/ente-io/museum/ente"
	"github.com/ente-io/stacktrace"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var knownInvalidEmailErrors = []string{
	"Invalid RCPT TO address provided",
	"Invalid domain name",
}

// Send sends an email
func Send(toEmails []string, fromName string, fromEmail string, subject string, htmlBody string, inlineImages []map[string]interface{}) error {
	azureClientId := viper.GetString("azure.client.id")
	if azureClientId != "" {
		log.Infof("Sending using azure from email: %s", fromEmail)
		res := SendViaAzure(toEmails, fromName, fromEmail, subject, htmlBody, inlineImages)
		log.Infof("result from SendViaAzure %s", res)
		return res
	} else {
		log.Infof("SMTP config %s", viper.GetStringMap("smtp"))
		smtpHost := viper.GetString("smtp.host")
		if smtpHost != "" {
			return sendViaSMTP(toEmails, fromName, fromEmail, subject, htmlBody, inlineImages)
		} else {
			return sendViaTransmail(toEmails, fromName, fromEmail, subject, htmlBody, inlineImages)
		}
	}
}

func sendViaSMTP(toEmails []string, fromName string, fromEmail string, subject string, htmlBody string, inlineImages []map[string]interface{}) error {
	if len(toEmails) == 0 {
		return ente.ErrBadRequest
	}

	smtpServer := viper.GetString("smtp.host")
	smtpPort := viper.GetString("smtp.port")
	smtpUsername := viper.GetString("smtp.username")
	smtpPassword := viper.GetString("smtp.password")
	smtpEmail := viper.GetString("smtp.email")
	smtpSenderName := viper.GetString("smtp.sender-name")

	var emailMessage string
	var auth smtp.Auth = nil
	if smtpUsername != "" && smtpPassword != "" {
		auth = smtp.PlainAuth("", smtpUsername, smtpPassword, smtpServer)
	}

	// Construct 'emailAddresses' with comma-separated email addresses
	var emailAddresses string
	for i, email := range toEmails {
		if i != 0 {
			emailAddresses += ","
		}
		emailAddresses += email
	}

	// If a sender email is provided use it instead of the fromEmail.
	if smtpEmail != "" {
		fromEmail = smtpEmail
	}
	// If a sender name is provided use it instead of the fromName.
	if smtpSenderName != "" {
		fromName = smtpSenderName
	}

	header := "From: " + fromName + " <" + fromEmail + ">\n" +
		"To: " + emailAddresses + "\n" +
		"Subject: " + subject + "\n" +
		"MIME-Version: 1.0\n" +
		"Content-Type: multipart/related; boundary=boundary\n\n" +
		"--boundary\n"
	htmlContent := "Content-Type: text/html; charset=us-ascii\n\n" + htmlBody + "\n"

	emailMessage = header + htmlContent

	if inlineImages == nil {
		emailMessage += "--boundary--"
	} else {
		for _, inlineImage := range inlineImages {

			emailMessage += "--boundary\n"
			var mimeType = inlineImage["mime_type"].(string)
			var contentID = inlineImage["cid"].(string)
			var imgBase64Str = inlineImage["content"].(string)

			var image = "Content-Type: " + mimeType + "\n" +
				"Content-Transfer-Encoding: base64\n" +
				"Content-ID: <" + contentID + ">\n" +
				"Content-Disposition: inline\n\n" + imgBase64Str + "\n"

			emailMessage += image
		}
		emailMessage += "--boundary--"
	}

	// Send the email to each recipient
	for _, toEmail := range toEmails {
		err := smtp.SendMail(smtpServer+":"+smtpPort, auth, fromEmail, []string{toEmail}, []byte(emailMessage))
		if err != nil {
			errMsg := err.Error()
			for i := range knownInvalidEmailErrors {
				if strings.Contains(errMsg, knownInvalidEmailErrors[i]) {
					return stacktrace.Propagate(ente.NewBadRequestWithMessage(fmt.Sprintf("Invalid email %s", toEmail)), errMsg)
				}
			}
			return stacktrace.Propagate(err, "")
		}
	}

	return nil
}

func sendViaTransmail(toEmails []string, fromName string, fromEmail string, subject string, htmlBody string, inlineImages []map[string]interface{}) error {
	if len(toEmails) == 0 {
		return ente.ErrBadRequest
	}

	authKey := viper.GetString("transmail.key")
	silent := viper.GetBool("internal.silent")
	if authKey == "" || silent {
		log.Infof("Skipping sending email to %s: %s", toEmails[0], subject)
		return nil
	}

	var to []ente.ToEmailAddress
	for _, toEmail := range toEmails {
		to = append(to, ente.ToEmailAddress{EmailAddress: ente.EmailAddress{Address: toEmail}})
	}
	mail := &ente.Mail{
		BounceAddress: ente.TransmailEndBounceAddress,
		From:          ente.EmailAddress{Address: fromEmail, Name: fromName},
		Subject:       subject,
		Htmlbody:      htmlBody,
		InlineImages:  inlineImages,
	}
	if len(toEmails) == 1 {
		mail.To = to
	} else {
		mail.Bcc = to
	}
	postBody, err := json.Marshal(mail)
	if err != nil {
		return stacktrace.Propagate(err, "")
	}
	reqBody := bytes.NewBuffer(postBody)
	client := &http.Client{}
	req, err := http.NewRequest("POST", ente.TransmailEndPoint, reqBody)
	if err != nil {
		return stacktrace.Propagate(err, "")
	}
	req.Header.Set("accept", "application/json")
	req.Header.Set("content-type", "application/json")
	req.Header.Set("authorization", authKey)
	_, err = client.Do(req)
	return stacktrace.Propagate(err, "")
}

func SendTemplatedEmail(to []string, fromName string, fromEmail string, subject string, templateName string, templateData map[string]interface{}, inlineImages []map[string]interface{}) error {
	body, err := getMailBody(templateName, templateData)
	if err != nil {
		return stacktrace.Propagate(err, "")
	}

	return Send(to, fromName, fromEmail, subject, body, inlineImages)
}

func SendTemplatedEmailV2(to []string, fromName string, fromEmail string, subject string, baseTemplate, templateName string, templateData map[string]interface{}, inlineImages []map[string]interface{}) error {
	body, err := getMailBodyWithBase(baseTemplate, templateName, templateData)
	if err != nil {
		return stacktrace.Propagate(err, "")
	}

	return Send(to, fromName, fromEmail, subject, body, inlineImages)
}

func GetMaskedEmail(email string) string {
	at := strings.LastIndex(email, "@")
	if at >= 0 {
		username, domain := email[:at], email[at+1:]
		maskedUsername := ""
		for i := 0; i < len(username); i++ {
			maskedUsername += "*"
		}
		return maskedUsername + "@" + domain
	} else {
		// Should ideally never happen, there should always be an @ symbol
		return "[invalid_email]"
	}
}

// getMailBody generates the mail html body from provided template and data
func getMailBody(templateName string, templateData map[string]interface{}) (string, error) {
	htmlbody := new(bytes.Buffer)
	t := template.Must(template.New(templateName).ParseFiles("mail-templates/" + templateName))
	err := t.Execute(htmlbody, templateData)
	if err != nil {
		return "", stacktrace.Propagate(err, "")
	}
	return htmlbody.String(), nil
}

// getMailBody generates the mail HTML body from the provided template and data, supporting inheritance
func getMailBodyWithBase(baseTemplateName, templateName string, templateData map[string]interface{}) (string, error) {
	htmlBody := new(bytes.Buffer)

	// Define paths for the base template and the specific template
	baseTemplate := "mail-templates/" + baseTemplateName
	specificTemplate := "mail-templates/" + templateName

	parts := strings.Split(baseTemplate, "/")
	lastPart := parts[len(parts)-1]
	baseTemplateID := strings.TrimSuffix(lastPart, path.Ext(lastPart))

	// Parse the base and specific templates together
	t, err := template.ParseFiles(baseTemplate, specificTemplate)
	if err != nil {
		return "", stacktrace.Propagate(err, "failed to parse templates")
	}

	// Execute the base template with the provided data
	err = t.ExecuteTemplate(htmlBody, baseTemplateID, templateData)
	if err != nil {
		return "", stacktrace.Propagate(err, "failed to execute template")
	}

	return htmlBody.String(), nil
}
func SendViaAzure(toEmails []string, fromName string, fromEmail string, subject string, htmlBody string, inlineImages []map[string]interface{}) error {
	// Get an access token
	token, err := getAccessToken()
	if err != nil {
		return stacktrace.Propagate(err, "")
	}

	// Build the 'toRecipients' array
	var toRecipients []map[string]interface{}
	for _, toEmail := range toEmails {
		toRecipients = append(toRecipients, map[string]interface{}{
			"emailAddress": map[string]string{
				"address": toEmail,
			},
		})
	}

	// Build the email message
	emailMessage := map[string]interface{}{
		"message": map[string]interface{}{
			"subject": subject,
			"body": map[string]string{
				"contentType": "HTML",
				"content":     htmlBody,
			},
			"toRecipients": toRecipients,
		},
		"saveToSentItems": true,
	}

	// Only add attachments if inlineImages is not nil and not empty
	if inlineImages != nil && len(inlineImages) > 0 {
		var attachments []map[string]interface{}
		for _, img := range inlineImages {
			attachments = append(attachments, img)
		}
		emailMessage["message"].(map[string]interface{})["attachments"] = attachments
	}

	// Serialize the payload
	jsonData, err := json.Marshal(emailMessage)
	if err != nil {
		return stacktrace.Propagate(err, "")
	}

	// Send the email using Microsoft Graph API
	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s/sendMail", fromEmail)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return stacktrace.Propagate(err, "")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("Error sending mail %s", err)
		return stacktrace.Propagate(err, "")
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return stacktrace.Propagate(err, "")
	}

	return nil
}

func getAccessToken() (string, error) {
	azureClientId := viper.GetString("azure.client.id")
	azureClientSecret := viper.GetString("azure.client.secret")
	azureTenantId := viper.GetString("azure.tenant.id")
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", azureTenantId)
	data := url.Values{}
	data.Set("client_id", azureClientId)
	data.Set("scope", "https://graph.microsoft.com/.default")
	data.Set("client_secret", azureClientSecret)
	data.Set("grant_type", "client_credentials")

	req, err := http.NewRequest("POST", tokenURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("token request failed: %s", string(bodyBytes))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	token, ok := result["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("no access token in response")
	}

	return token, nil
}
