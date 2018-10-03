
rule m26bb_4264eb3732b96ed2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.4264eb3732b96ed2"
     cluster="m26bb.4264eb3732b96ed2"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virut virtob malicious"
     md5_hashes="['7d663266474831f817a1852aa62d6c342e9fb5c4','c0afa68e4ed743d1f235f838474faca58f794f4c','8ffccc3430789c3bbb385fe56170406f43b9bb73']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.4264eb3732b96ed2"

   strings:
      $hex_string = { ecaa6b1aa7ce0dd88bb907e5d601c033bdde78bbc1b451a36ab1ffd22baf3ef1f8b3cfd5a1dbf228ab1624090c501d8d29881ef858ebe72ad1fb70185d94877b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
