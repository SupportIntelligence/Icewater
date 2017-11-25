
rule k2321_03959250daa27916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.03959250daa27916"
     cluster="k2321.03959250daa27916"
     cluster_size="3"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma rontokbro"
     md5_hashes="['26c355d76ad08cc9e8309eefc633c640','4d7f8050e3710ea8e7dfd4a24346e891','c5d38b179f3767eea21da23f3f006d56']"

   strings:
      $hex_string = { b8e2d8ed139b944adcd377251eaf547a201207938a637cf86e252b437d090c5e37b02a0e6f80863a8feeb7bc46fd857fc656b2d6b5d5cd7e3d5cad1c2eba9d70 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
