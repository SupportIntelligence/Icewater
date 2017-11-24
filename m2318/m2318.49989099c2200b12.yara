
rule m2318_49989099c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.49989099c2200b12"
     cluster="m2318.49989099c2200b12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['303f2f6de654e7bede79b4a6d28b0528','3f57845e446ee5536c6b9d2ed8c2c02d','df1b802b8872bc79f3d42acdff208dbd']"

   strings:
      $hex_string = { 35393032383136433434334646414139443831463732333439444536433139373539324636434237314135413538303642443045313534323345363736323038 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
