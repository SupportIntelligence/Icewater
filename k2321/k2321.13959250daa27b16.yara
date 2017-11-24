
rule k2321_13959250daa27b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.13959250daa27b16"
     cluster="k2321.13959250daa27b16"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma rontokbro"
     md5_hashes="['52710421592284d4b91bfb0c666195de','652929b097ed86f6f017defd305615aa','c97f858ca3aee2f3ef70423794c1327d']"

   strings:
      $hex_string = { b8e2d8ed139b944adcd377251eaf547a201207938a637cf86e252b437d090c5e37b02a0e6f80863a8feeb7bc46fd857fc656b2d6b5d5cd7e3d5cad1c2eba9d70 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
