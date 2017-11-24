
rule n3e9_02408b2421134aba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.02408b2421134aba"
     cluster="n3e9.02408b2421134aba"
     cluster_size="51"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy delf advml"
     md5_hashes="['0b97db5980c1f2e324588708bd896c66','0ffc25e16cd92b11b03ce60af61dbcb8','cddb4e78a94a467c524a925d096561d0']"

   strings:
      $hex_string = { 5d61fabb9165f9b26070eaa103d1693092e54f31fef1ee903ac8cb6aaff01f25a486dc7fa006124dc7c101d49b67594a896b772a881db4caefa5a22ed0aef7e6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
