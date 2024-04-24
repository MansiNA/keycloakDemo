package org.vaadin.example;

import com.vaadin.flow.component.Html;
import com.vaadin.flow.component.html.H2;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.PageTitle;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.auth.AnonymousAllowed;
import jakarta.annotation.security.RolesAllowed;
/*import com.wontlost.ckeditor.Config;
import com.wontlost.ckeditor.Constants;
import com.wontlost.ckeditor.VaadinCKEditor;
import com.wontlost.ckeditor.VaadinCKEditorBuilder;*/

@PageTitle("FVM-Admin Tool")
@Route(value = "/userinfo", layout= MainLayout.class)
@RolesAllowed("USER")
public class UserInfoView extends VerticalLayout {

   // @Value("${ldap.urls}")
    //private String ldapUrls;

    public UserInfoView(){



        add(new H2("Hallo und willkommen"));

        String yourContent_notloggedin ="Auf dieser Seite werden Tools und Hilfsmittel bereitgestellt, um FVM-Tätigkeiten zu vereinfachen.<br />" +
                "Ebenso wird den Justizen ermöglicht, Informationen direkt aus der <b>eKP</b> bzw. <b>EGVP-E</b> zu entnehmen.<br />" +
                "Die sich aktuell noch in Planung befindlichen Funktionen sind mit <i>geplant</i> gekennzeichnet.<br />" +
                "Ideen, Anregungen oder Verbesserungsvorschläge sind herzlich willkommen!&#128512;<br /><br />" +
                "Bitte als erstes einloggen!<br /><br />" +
                "Viele Grüße<br /><b>Euer Dataport FVM-Team</b>" ;

        String yourContent_loggedin ="Auf dieser Seite werden Tools und Hilfsmittel bereitgestellt, um FVM-Tätigkeiten zu vereinfachen.<br />" +
                "Ebenso wird den Justizen ermöglicht, Informationen direkt aus der <b>eKP</b> bzw. <b>EGVP-E</b> zu entnehmen.<br />" +
                "Die sich aktuell noch in Planung befindlichen Funktionen sind mit <i>geplant</i> gekennzeichnet.<br />" +
                "Ideen, Anregungen oder Verbesserungsvorschläge sind herzlich willkommen!&#128512;<br /><br />" +
                "Bitte im linken Auswahlmenü die gewünschte Funktionalität auswählen.<br /><br />" +
                "Viele Grüße<br /><b>Euer Dataport FVM-Team</b>" ;

        Html html_notLoggedin = new Html("<text>" + yourContent_notloggedin + "</text>");
        Html html_Loggedin = new Html("<text>" + yourContent_loggedin + "</text>");

        add(html_notLoggedin,html_Loggedin);

/*        VaadinCKEditor classicEditor = new VaadinCKEditorBuilder().with(builder -> {
            builder.editorData = "<p>This is a classic editor sample.</p>";
            builder.editorType = Constants.EditorType.CLASSIC;
            builder.theme = Constants.ThemeType.DARK;
        }).createVaadinCKEditor();

        VaadinCKEditor preview = new VaadinCKEditorBuilder().with(builder -> {
            builder.editorData = classicEditor.getValue();
            builder.editorType = Constants.EditorType.BALLOON;
            builder.width = "70%";
            builder.config = new Config();
            builder.ghsEnabled = true;
            //  config.setImage(new String[][]{}, "", new String[]{}, new String[]{}, new String[]{});
            builder.readOnly = true;
        }).createVaadinCKEditor();

        classicEditor.addValueChangeListener(e->{
            preview.setValue(classicEditor.getValue());

        });

        Button save = new Button("save content text");
        save.addClickListener((event -> {
            //content.getElement().setProperty("innerHTML", preview.getContentText());
            String inhalt =  preview.getValue();
            System.out.println(inhalt);

        }));


        add(save);
        add(classicEditor);
        add(preview);*/




    }


}
