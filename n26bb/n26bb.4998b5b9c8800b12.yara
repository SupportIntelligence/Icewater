
rule n26bb_4998b5b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.4998b5b9c8800b12"
     cluster="n26bb.4998b5b9c8800b12"
     cluster_size="66"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="autoit malicious asvcs"
     md5_hashes="['471da49181e5b5dcabb507f0adc9904332e5f15c','06ce29829a3cd2b40e2c980b228c3232d8a613f1','b809dde237144536d59f5f9b411c35be1dee3a7b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.4998b5b9c8800b12"

   strings:
      $hex_string = { 1b104996515a5d4e32164d7f22dc856b82ec1a751572b0d45e94e68055b23c5bc186d1c626c2cf27adea34180cb6442b1c84f0d7bca3178b25130881c99ccc69 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
