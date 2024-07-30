package site.dadangsinhhoc.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;

@Configuration
@EnableWebMvc
public class SwaggerConfig implements WebMvcConfigurer {

    @Bean
    public Docket api() {
        try {
            Docket docket = new Docket(DocumentationType.SWAGGER_2)
                    .select()
                    .apis(RequestHandlerSelectors.basePackage("com.example.dadangsinhhoc"))
                    .paths(PathSelectors.regex("/.*"))
                    .build().apiInfo(apiInfo());;

            System.out.println("\n\nSwagger UI in: http://localhost:8080/swagger-ui/index.html#/");
            System.out.println("Login with Admin:");
            System.out.println("\tUsername and passwork: admin");
            System.out.println("Login with User:");
            System.out.println("\tUsername and passwork: user");
            System.out.println("\nPhpmyadmin in: http://localhost/phpmyadmin/index.php?route=/database/structure&db=dongthucvat   ");
            System.out.println("\tUsername: root");
            System.out.println("\tPasswork: admin123");

            return docket;
        } catch (Exception e) {
            System.err.println("Failt when init Swagger: " + e.getMessage());
            throw e;
        }
    }

    private ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title("Geeks API")
                .description("Demonstration of all write portal API")
                .version("1.0")
                .build();
    }
}