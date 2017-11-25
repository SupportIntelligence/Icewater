
rule k3f7_371195aede630b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.371195aede630b12"
     cluster="k3f7.371195aede630b12"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe html redirector"
     md5_hashes="['2b1f33b77adead9d907482557805acd8','2f0e2ec4cf1529fb5756a6a7a52202c5','a7e0572d338140eb6085ca47fe0ce88c']"

   strings:
      $hex_string = { 3e3c696d67207372633d22696d616765732f706978656c5f7472616e732e6769662220626f726465723d22302220616c743d22222077696474683d2231303025 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
