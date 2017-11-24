
rule k2321_0a50c45c5e6748ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0a50c45c5e6748ba"
     cluster="k2321.0a50c45c5e6748ba"
     cluster_size="30"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy backdoor"
     md5_hashes="['1032257b6e8d8f7dd7475fc1e2dffb3d','15cd95bf68dbd855644d084ebb834dae','943d0e6f60b593434b9495e09f3b403b']"

   strings:
      $hex_string = { cce5f1718e1ebc3c9373e936112a2f507434a625379610d166a51a91edb2d9281400ba6a69b75aa19fbf977f9d40acd0f2ef2ebd6182ea39eb70037230463188 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
