
rule m3e9_6314b4a0d1bb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6314b4a0d1bb0912"
     cluster="m3e9.6314b4a0d1bb0912"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack malicious"
     md5_hashes="['0830c7bc987d767a9462842097643dc8','1a2b164790f1bb576983741505b32841','fcca2e3457d6063d75898754fea66b77']"

   strings:
      $hex_string = { dfbaebee93d67d59643e35a6818bb1d8960dfcaa9abf07925ab1f9e29caef2a2e5cc6930b6c3489ba5d23656e16a2da39bd5dbda9d3b6fd4e93e0459de730b4b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
