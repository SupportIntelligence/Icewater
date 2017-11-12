import "hash"

rule j3e9_230f66f65cdb6992
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.230f66f65cdb6992"
     cluster="j3e9.230f66f65cdb6992"
     cluster_size="921"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre generickd waski"
     md5_hashes="['001488f785911343f931f0088bba95cf','0059d74e093267df8dbd6005f13b44fe','0d61a884530fa9a0beeb5f2d31f5e42e']"


   condition:
      
      filesize > 16384 and filesize < 65536
      and hash.md5(0,4096) == "8ccde31f02f9ae2a19bc501b7a1c21db"
}

