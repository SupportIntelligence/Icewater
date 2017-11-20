
rule k3f4_20a454d69ba91114
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f4.20a454d69ba91114"
     cluster="k3f4.20a454d69ba91114"
     cluster_size="69"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="krypt bladabindi malicious"
     md5_hashes="['00fbda851994aad96fb6246d22308464','0502602d317c92b9ab331f11604bfee9','3f8907563b5021b51c57d2b0e9ce24fd']"

   strings:
      $hex_string = { 03e1120d0809018705f60619015d132f0819016213370811036d133e088100d00f850191007613140711037f134408190186044a08310295135608e900a513b7 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
