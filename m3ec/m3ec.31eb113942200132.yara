
rule m3ec_31eb113942200132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.31eb113942200132"
     cluster="m3ec.31eb113942200132"
     cluster_size="70"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['05616af3abaad3dc228208e27cf06e68','06ef0b601b3712b5a47aca688f2a33da','796a6a8b39b554e5794c1565f0d65b22']"

   strings:
      $hex_string = { 002e000a0006010a00550073006100670065003a0020002500310021007300210020005b005b006e0061006d0065003d005d003c0073007400720069006e0067 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
