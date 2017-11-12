import "hash"

rule k3e9_073c3f59526b491a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.073c3f59526b491a"
     cluster="k3e9.073c3f59526b491a"
     cluster_size="20"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="servstart cfecc nitol"
     md5_hashes="['2b55360dadc79a78b607a53ed1155167','62becb89dcd108e30478e05b0d7b8156','d0ecf90cee23f48f31133c3550dfd195']"


   condition:
      
      filesize > 65536 and filesize < 262144
      and hash.md5(16384,16384) == "45ccf91d575e168af4da1a887a475b27"
}

