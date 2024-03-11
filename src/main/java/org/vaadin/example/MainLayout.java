package org.vaadin.example;

import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.applayout.AppLayout;
import com.vaadin.flow.component.applayout.DrawerToggle;
import com.vaadin.flow.component.avatar.Avatar;
import com.vaadin.flow.component.contextmenu.MenuItem;
import com.vaadin.flow.component.html.*;
import com.vaadin.flow.component.icon.Icon;
import com.vaadin.flow.component.menubar.MenuBar;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.orderedlayout.FlexComponent;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.Scroller;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.sidenav.SideNav;
import com.vaadin.flow.component.sidenav.SideNavItem;
import com.vaadin.flow.router.RouteParameters;
import com.vaadin.flow.router.RouterLink;
import com.vaadin.flow.server.StreamResource;
import com.vaadin.flow.server.auth.AccessAnnotationChecker;
import com.vaadin.flow.theme.lumo.LumoUtility;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.vaadin.example.entity.User;
import org.vaadin.example.security.AuthenticatedUser;
import org.vaadin.example.service.UserService;

import java.io.ByteArrayInputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;


/**
 * The main view is a top-level placeholder for other views.
 */
@Slf4j
public class MainLayout extends AppLayout {

    private H3 viewTitle;
    private AuthenticatedUser authenticatedUser;
    private AccessAnnotationChecker accessChecker;
    private UserService userService;

    // Map to associate URLs with view classes
    private Map<String, Class<? extends Component>> urlToViewMap = new HashMap<>();

    Image image = new Image("images/telefonica.svg", "Telefonica");

    private static final Logger logInfo = LoggerFactory.getLogger(MainLayout.class);
    public static String userName;
    public static boolean isAdmin;
    private LoginView loginView;

    public MainLayout(AuthenticatedUser authenticatedUser, AccessAnnotationChecker accessChecker, UserService userService) {
        this.authenticatedUser = authenticatedUser;
        this.accessChecker = accessChecker;
        this.userService = userService;

        setPrimarySection(Section.DRAWER);
        addDrawerContent();
        addHeaderContent();
     //   createHeader();
        isAdmin = checkAdminRole();
    }

    private void addHeaderContent() {
        log.info("Starting addHeaderContent() in mainlayout");

        DrawerToggle toggle = new DrawerToggle();
        toggle.setAriaLabel("Menu toggle");

        viewTitle = new H3();
        viewTitle.setText("");
        //viewTitle.addClassNames(LumoUtility.FontSize.LARGE, LumoUtility.Margin.NONE);

        Span version= new Span("V1.5");

        image.setHeight("60px");
        image.setWidth("150px");

        HorizontalLayout header= new HorizontalLayout(viewTitle,image, version);
        header.setDefaultVerticalComponentAlignment(FlexComponent.Alignment.CENTER);
        header.expand(viewTitle);
        header.setWidthFull();
        header.addClassNames("py-0", "px-m");


        addToNavbar(true, toggle, header);
        log.info("Ending addHeaderContent() in mainlayout");


    }

    private void addDrawerContent() {
        log.info("Starting addDrawerContent() in mainlayout");
        System.out.println("Starting addDrawerContent() in mainlayout");
        RouterLink link = new RouterLink("login", LoginView.class);
        H2 appName = new H2("PIT");
        appName.addClassNames("text-l","m-m");
        appName.addClassNames(LumoUtility.FontSize.LARGE, LumoUtility.Margin.NONE);
        Header header = new Header(appName);

        Optional<User> maybeUser = authenticatedUser.get();
        if (maybeUser.isPresent()) {

          //  Scroller scroller = new Scroller(createTree());
            addToDrawer(header, createFooter());

        } else
        {
            //loginView = new LoginView(authenticatedUser);
            loginView = new LoginView();
            addToDrawer(new VerticalLayout(link));
           // addToDrawer(new VerticalLayout(loginView));
        }

        //Scroller scroller = new Scroller(createTree());
        //scroller.addClassNames("AboutView");

        log.info("Ending addDrawerContent() in mainlayout");



    }

    private void navigateToView(String url) {
        log.info("Starting navigateToView() in mainlayout");
        if (url != null) {
            getUI().ifPresent(ui -> {
                String route = "/" + url; // Assuming your route names match the URLs
                ui.navigate(route);
            });
        }
        log.info("Ending navigateToView() in mainlayout");
    }

    private Footer createFooter() {
        log.info("Starting createFooter() in mainlayout");
        Footer layout = new Footer();

        Optional<User> maybeUser = authenticatedUser.get();
        if (maybeUser.isPresent()) {
            User user = maybeUser.get();

            Avatar avatar = new Avatar(user.getName());
            avatar.setThemeName("xsmall");
            avatar.getElement().setAttribute("tabindex", "-1");

            MenuBar userMenu = new MenuBar();
            userMenu.setThemeName("tertiary-inline contrast");

            MenuItem userName = userMenu.addItem("");
            Div div = new Div();
            div.add(avatar);
            div.add(user.getName());
            div.add(new Icon("lumo", "dropdown"));
            div.getElement().getStyle().set("display", "flex");
            div.getElement().getStyle().set("align-items", "center");
            div.getElement().getStyle().set("gap", "var(--lumo-space-s)");
            userName.add(div);
            userName.getSubMenu().addItem("Sign out", e -> {
                authenticatedUser.logout();
            });

            layout.add(userMenu);
        } else {
            Anchor loginLink = new Anchor("login", "Sign in");
            layout.add(loginLink);
        }
        log.info("Ending createFooter() in mainlayout");
        return layout;
    }

    @Override
    protected void afterNavigation() {
        log.info("Staring afterNavigation() in mainlayout");
      //  viewTitle.setText(getCurrentPageTitle());
        super.afterNavigation();

        if (loginView != null) {
         //   loginView.openLoginOverlay();
        }
      //  viewTitle.setText(selectedProject.getName());


        log.info("Ending afterNavigation() in mainlayout");
    }

    public static boolean checkAdminRole() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication !=  null  && !(authentication instanceof AnonymousAuthenticationToken)) {
            Object principal = authentication.getPrincipal();
            if (principal instanceof UserDetails) {
                UserDetails userDetails = (UserDetails) principal;
                return userDetails.getAuthorities().stream().anyMatch(authority -> authority.getAuthority().equals("ROLE_ADMIN"));
            }
        }
        return false;
    }

}
