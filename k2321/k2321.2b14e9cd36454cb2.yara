
rule k2321_2b14e9cd36454cb2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2b14e9cd36454cb2"
     cluster="k2321.2b14e9cd36454cb2"
     cluster_size="10"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba crypt emotet"
     md5_hashes="['05ce0e41277cc58ec31ef273f2b7ce38','4387a83490ae922228e5c937596fd20b','ff5b43a6d8d5c22f7d3ce358e4e49ae9']"

   strings:
      $hex_string = { abae6af0423290643fe2985cd28ba41f732c2f2924e927483b6b25198c6426f5912b75c81b54b16c927e8ab48916c3a8ce02964c722a7b11e5443746b29d882d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
