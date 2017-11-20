
rule m2321_113d6810dceb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.113d6810dceb0932"
     cluster="m2321.113d6810dceb0932"
     cluster_size="36"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="squarenet riskware unwanted"
     md5_hashes="['01c60aaf543d773b413b279f146d6bc6','04487229a75d7467324c22b014125651','3b15101ed16e5a446b0856ee53a12f3e']"

   strings:
      $hex_string = { 291de60ea06e3c9922f85bc038b43525586c87d07c0a7dd90815ae6f3d1fe509663facfea614429e4020b0d31e2b4559546ab778d507e80381e4b2561a3b449d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
