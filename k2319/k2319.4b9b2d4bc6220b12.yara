
rule k2319_4b9b2d4bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.4b9b2d4bc6220b12"
     cluster="k2319.4b9b2d4bc6220b12"
     cluster_size="483"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['6269d51257467905fb1b69e2115ae42971160f6d','88196d88535745c642ca6201231c186fc691f9fd','0aca5ba7d0057ff10f7e17c54660eddff55f1274']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.4b9b2d4bc6220b12"

   strings:
      $hex_string = { 3c21646f63747970652068746d6c207075626c696320222d2f2f5733432f2f4454442048544d4c20342e3031205472616e736974696f6e616c2f2f454e223e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
