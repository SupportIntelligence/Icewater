import "hash"

rule m3ed_31ea5ed29b4b4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.31ea5ed29b4b4912"
     cluster="m3ed.31ea5ed29b4b4912"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['d68bd09cbc0f2661cfdb1231339f7ee5', 'cbaa45c9261b0ce62636cffbf199ef0d', 'cc24ce7f3abe8b87349e0d4ab84aff74']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(53248,1024) == "2e1fd58e17e7ebd34f1ab92566daa558"
}

