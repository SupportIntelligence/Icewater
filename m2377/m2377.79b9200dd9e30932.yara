
rule m2377_79b9200dd9e30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.79b9200dd9e30932"
     cluster="m2377.79b9200dd9e30932"
     cluster_size="129"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['02e316f67a345312c8104fd0033340fe','031ff1f5590bcd085cb90ac4efe539ff','140f7ed9331f701d99d771978f5756c7']"

   strings:
      $hex_string = { 44333638374644414439364438343343303546373342374336453042343133373043314139303536384132313936393732373932453845453242463130423534 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
