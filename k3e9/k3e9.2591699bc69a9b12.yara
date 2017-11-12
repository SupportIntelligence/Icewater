import "hash"

rule k3e9_2591699bc69a9b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2591699bc69a9b12"
     cluster="k3e9.2591699bc69a9b12"
     cluster_size="90"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="parite pate pinfi"
     md5_hashes="['00abb7877d8517def950928446d95399','0587b5f4c03abeaab5314ed967bf5cce','27be2e964b91d553c2975d9eb6a4ea4c']"


   condition:
      
      filesize > 262144 and filesize < 1048576
      and hash.md5(262144,65536) == "b97ea0f8fdf5ddffa7cba0001d73fd86"
}

