
rule m3f7_5c9b208ec2210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.5c9b208ec2210912"
     cluster="m3f7.5c9b208ec2210912"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['2aa1782b11a87a36ff1e51acc2f5000d','3f22d0d7d36394d1996eedd009871dd8','b7870be54e1e5c807a7ca8ffb21d2268']"

   strings:
      $hex_string = { 31363437384645414435354239374641333432303931453341364630324335304545414344443443344332393737433031363844333842363832424545424634 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
