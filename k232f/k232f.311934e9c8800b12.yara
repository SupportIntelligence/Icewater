
rule k232f_311934e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k232f.311934e9c8800b12"
     cluster="k232f.311934e9c8800b12"
     cluster_size="19054"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html framer"
     md5_hashes="['03ca278fdccd52383aaa68805c3dd073da52eba6','2d914bad326f1037194cc6bb98c90ef7c781de91','db5174123dfd3004ddf979c8464553d69efc900e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k232f.311934e9c8800b12"

   strings:
      $hex_string = { 7d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
