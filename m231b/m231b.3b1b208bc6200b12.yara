
rule m231b_3b1b208bc6200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.3b1b208bc6200b12"
     cluster="m231b.3b1b208bc6200b12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html inor"
     md5_hashes="['43f807e75e4d07dffe3f4e2beeb200e7','8b25b9532a5339983e0c7609dbe278f3','f5bbbed52c67a57a0cd2313012f744e5']"

   strings:
      $hex_string = { 39454331453145333437393738413342434446333930353736433236463743334631444235324544413431373638323230303541383635374530423839303842 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
