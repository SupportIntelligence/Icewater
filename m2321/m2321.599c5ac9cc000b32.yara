
rule m2321_599c5ac9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.599c5ac9cc000b32"
     cluster="m2321.599c5ac9cc000b32"
     cluster_size="7"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob heuristic"
     md5_hashes="['4b3fca937959dd6ead86a821592227ec','6d5a271cad4ed501139fa6de260cf019','e887ab129c75c00f2e527d818d9d58f0']"

   strings:
      $hex_string = { d819a52b34e6fbc842a25e9b63242a50b93bbef5dbe51c3692e1d7ed06e2f651c11da4894d333f470b93a9ac65960e3c2666820573d102a0d094c2cc7008b22f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
