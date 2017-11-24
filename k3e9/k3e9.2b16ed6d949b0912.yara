
rule k3e9_2b16ed6d949b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b16ed6d949b0912"
     cluster="k3e9.2b16ed6d949b0912"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy emotet"
     md5_hashes="['19d26a13c7de9467ffba69efff1d40d7','1ad725a6cc0859eecb439d42a7ba7f56','f3239229063c9345db45814ed64c220b']"

   strings:
      $hex_string = { 79b6da3a57639ba7b595ea6cf375f60581f6b220fba260c762bd7389a1b1dcd0b42ca4694568f3cab0e6d56197d64434af8dbcb42ef2d2faa84b1ba32f6f8ab9 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
