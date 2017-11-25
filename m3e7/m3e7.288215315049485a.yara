
rule m3e7_288215315049485a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.288215315049485a"
     cluster="m3e7.288215315049485a"
     cluster_size="149"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbkrypt qmlfrt injector"
     md5_hashes="['07bb4c9528f53400a23ee203cd7cc85c','f0e7ce02f499c297c87ee0567241488a','37117497b042bb0df92069a308bfaba9']"

   strings:
      $hex_string = { 152a78918b8c46e5d07bdd6747402244dec25511e7a47f1b64b5cbf9c39aa84f8a13c96052b2e1f0ebc54afe868805c6892fb8a192dc37b4202181ff8d23cf99 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
