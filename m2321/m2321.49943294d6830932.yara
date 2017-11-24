
rule m2321_49943294d6830932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.49943294d6830932"
     cluster="m2321.49943294d6830932"
     cluster_size="14"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="elemental elementa jtvn"
     md5_hashes="['27b0b43f2a67e2a6e12dc10761d58bef','376540e1a7622ef36a00280bed2ac209','de780483ccc52c3cfe7566e89e955712']"

   strings:
      $hex_string = { 7e2466af93b35f2867fe859239e5a357f2d19065cee691503386c7f17d2ab9761ec5ddaaf91dc3a88c880b48801637fc5c0d290ab51d7742b02ba1cf69decbda }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
