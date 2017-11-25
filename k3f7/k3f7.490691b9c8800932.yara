
rule k3f7_490691b9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.490691b9c8800932"
     cluster="k3f7.490691b9c8800932"
     cluster_size="21"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector script html"
     md5_hashes="['0c5f3f7ca87233c23eb12adbbcdb2c91','2acc74ebb0cb79d872314d00cf41ba34','d6ec6c1bf67ecda98615333a57d3bdc4']"

   strings:
      $hex_string = { e7bec6b5ead3c5bbddd4a4b6a9b7fecef1a1a322202f3e0d0a3c7374796c6520747970653d22746578742f637373223e0d0a626f6479207b6d617267696e3a30 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
