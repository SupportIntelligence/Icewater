
rule k3f7_6d26fca9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.6d26fca9c8800912"
     cluster="k3f7.6d26fca9c8800912"
     cluster_size="26"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html script"
     md5_hashes="['02622a1cc88f98488298286731fc3422','0788036c1a274c021f86d015298ee84a','af02cfaea98e006568a84960a80bffb3']"

   strings:
      $hex_string = { bb2fd184d0b0d0bad1813a283334313229203c2f7370616e3e3c7374726f6e67207374796c653d226c696e652d6865696768743a20312e33656d3b223e393038 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
