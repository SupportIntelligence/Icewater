
rule o3e9_39b134469fa30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.39b134469fa30b12"
     cluster="o3e9.39b134469fa30b12"
     cluster_size="11"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonstr malicious unwanted"
     md5_hashes="['196c1b22b41338f6eb91aa8c7ef75536','38e3c2ad1cdca0c2928191d2868774fb','f2e0bbc824e2cc7555ff0d00d9ba0aab']"

   strings:
      $hex_string = { 52eff544479da1fbced174c6e95ac01ac3a265b490137e41b51491021172801e38e6e8de285ee766be5c24a04eb8d4a922675fc26ea4bd20689bba4519f969ec }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
