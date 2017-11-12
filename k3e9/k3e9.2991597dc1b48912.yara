import "hash"

rule k3e9_2991597dc1b48912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2991597dc1b48912"
     cluster="k3e9.2991597dc1b48912"
     cluster_size="10449"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="adload nsis trojandownloader"
     md5_hashes="['000a6df3f3350a59bda66ebfe58dfbaa','00149b95899f13c084eb4f95c7f84647','0113364bac9b3a777ba03e44c6135f59']"


   condition:
      
      filesize > 65536 and filesize < 262144
      and hash.md5(16384,16384) == "4210520ff714c944b770ca08e874ee4d"
}

