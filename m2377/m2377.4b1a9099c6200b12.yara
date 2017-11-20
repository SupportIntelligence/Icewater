
rule m2377_4b1a9099c6200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.4b1a9099c6200b12"
     cluster="m2377.4b1a9099c6200b12"
     cluster_size="8"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['05bcd4594f8c5d565347d89d063d6e56','2f12791a6cacffada02a4c7e78b9ffcc','e85e3c14d7ade1245a5a830449658aeb']"

   strings:
      $hex_string = { 42363139454331453145333437393738413342434446333930353736433236463743334631444235324544413431373638323230303541383635374530423839 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
