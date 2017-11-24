
rule o3e9_39b2c953c3d26992
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.39b2c953c3d26992"
     cluster="o3e9.39b2c953c3d26992"
     cluster_size="49"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr malicious"
     md5_hashes="['06e4862688ff7f22c08ea63c397e32ad','0c8cf135f02142ba2ff5c79d9b561df5','5edd97d4d46bcc28402375db5da274fc']"

   strings:
      $hex_string = { 8de003fc9068d8a592626ec00a7507365e3cf5359b01d229b76af9e672fd4a09b8da2b1a3112241c14d4efbf544b3a5f2d951030e41ec9772afe33f3648b97b5 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
