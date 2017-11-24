
rule k2321_211b1cc1cc000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.211b1cc1cc000932"
     cluster="k2321.211b1cc1cc000932"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nitol servstart heuristic"
     md5_hashes="['01f97a1c5b446779ff990a87316b5937','1b36af25c9f7e784638dd60565f53013','f21138f6a66cdda92960779d5888dd5f']"

   strings:
      $hex_string = { ee1646b56d31e3becf97866b3635a1ecf676222e0e3ec2db51e9b0921713f371a4b77790999594825c14eb5ffc5eb1981e09c3967d247a21d9a31ec0fbe89c87 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
