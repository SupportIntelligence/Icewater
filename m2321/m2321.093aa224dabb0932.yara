
rule m2321_093aa224dabb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.093aa224dabb0932"
     cluster="m2321.093aa224dabb0932"
     cluster_size="201"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['00dfaa22e6ba4620480c428dab3fe2a9','03217a94dcc71f6d40fd8b0e84ded3dc','0f931944473787abbde01418f88490b0']"

   strings:
      $hex_string = { 9897ac605ec7eeecf21499234c8e6800130325c44b3a6d3e662d11dbfb3481d63feda7aaf5ddebf1683cd1839069dfb150ef92fa58a3cd217882deae7e87da0f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
