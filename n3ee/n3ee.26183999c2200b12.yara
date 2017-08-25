import "hash"

rule n3ee_26183999c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ee.26183999c2200b12"
     cluster="n3ee.26183999c2200b12"
     cluster_size="2274 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="elex malicious snarasite"
     md5_hashes="['1833a345de458ccef92f2fa1af4ab734', '1679ff934335a9ad3b0747a991655328', '068c60f6bec2f6d3a80941e09c319b17']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(433664,1536) == "9cfe8db5a2d8f1ba66102ccd729b452c"
}

