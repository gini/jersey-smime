package com.github.joschi.jersey.security.doseta;

import com.github.joschi.jersey.annotations.security.doseta.After;
import com.github.joschi.jersey.annotations.security.doseta.Verifications;
import com.github.joschi.jersey.annotations.security.doseta.Verify;
import org.jboss.resteasy.annotations.interception.HeaderDecoratorPrecedence;
import org.jboss.resteasy.client.ClientResponse;
import org.jboss.resteasy.core.ResourceMethod;
import org.jboss.resteasy.core.ServerResponse;
import org.jboss.resteasy.spi.Failure;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.interception.AcceptedByMethod;
import org.jboss.resteasy.spi.interception.ClientExecutionContext;
import org.jboss.resteasy.spi.interception.ClientExecutionInterceptor;
import org.jboss.resteasy.spi.interception.PreProcessInterceptor;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.ext.Provider;
import java.lang.reflect.Method;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@Provider
@HeaderDecoratorPrecedence
public class DigitalVerificationHeaderDecorator implements ClientExecutionInterceptor, PreProcessInterceptor, AcceptedByMethod
{
   protected Verify verify;
   protected Verifications verifications;

   public boolean accept(Class declaring, Method method)
   {
      verify = (Verify) method.getAnnotation(Verify.class);
      verifications = (Verifications) method.getAnnotation(Verifications.class);

      return verify != null || verifications != null;
   }

   @Override
   public ClientResponse execute(ClientExecutionContext ctx) throws Exception
   {
      ClientResponse response = ctx.proceed();
      response.getAttributes().put(Verifier.class.getName(), create());
      return response;
   }

   @Override
   public ServerResponse preProcess(HttpRequest request, ResourceMethod method) throws Failure, WebApplicationException
   {
      request.setAttribute(Verifier.class.getName(), create());
      return null;
   }

   public Verifier create()
   {
      // Currently we create verifier every time so that the verifications can hold state related to failures
      // todo create a VerifyResult object for each verification.
      Verifier verifier = new Verifier();
      if (verify != null)
      {
         Verification v = createVerification(verify);
         verifier.getVerifications().add(v);
      }
      if (verifications != null)
      {
         for (Verify ver : verifications.value())
         {
            Verification v = createVerification(ver);
            verifier.getVerifications().add(v);
         }
      }
      return verifier;
   }

   protected Verification createVerification(Verify v)
   {
      Verification verification = new Verification();
      if (v.identifierName() != null && !v.identifierName().trim().equals(""))
         verification.setIdentifierName(v.identifierName());
      if (v.identifierValue() != null && !v.identifierValue().trim().equals(""))
         verification.setIdentifierValue(v.identifierValue());

      verification.setIgnoreExpiration(v.ignoreExpiration());
      After staleAfter = v.stale();
      if (staleAfter.seconds() > 0
              || staleAfter.minutes() > 0
              || staleAfter.hours() > 0
              || staleAfter.days() > 0
              || staleAfter.months() > 0
              || staleAfter.years() > 0)
      {
         verification.setStaleCheck(true);
         verification.setStaleSeconds(staleAfter.seconds());
         verification.setStaleMinutes(staleAfter.minutes());
         verification.setStaleHours(staleAfter.hours());
         verification.setStaleDays(staleAfter.days());
         verification.setStaleMonths(staleAfter.months());
         verification.setStaleYears(staleAfter.years());
      }
      verification.setBodyHashRequired(v.bodyHashRequired());
      return verification;
   }

}
