
rule m2377_3c9b008cc2210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.3c9b008cc2210912"
     cluster="m2377.3c9b008cc2210912"
     cluster_size="7"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['288c77b1351faacbc3d514e0bca5d8b8','41e1ef8736bbfe7c8bdd9ee423ac2121','c1757181dfec212b06de5a10fa610708']"

   strings:
      $hex_string = { 44333638374644414439364438343343303546373342374336453042343133373043314139303536384132313936393732373932453845453242463130423534 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
