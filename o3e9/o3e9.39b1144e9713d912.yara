
rule o3e9_39b1144e9713d912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.39b1144e9713d912"
     cluster="o3e9.39b1144e9713d912"
     cluster_size="249"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr malicious"
     md5_hashes="['0084b7eb77e936ce374f920119782fe2','036a10b8c5cf6b7d1556d3ca9390de85','0faba771d62adc5f28dadbebdf16a199']"

   strings:
      $hex_string = { d70f7d9b87b9d2cea79fe8e2e41824c07c929ec381e561fbf1afaab4163a5e58a3e799c1345ae92dbb6b7750b20ca986ee8802a8892909d1657b9490f9c842fd }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
