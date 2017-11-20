
rule k3f9_46c61d22992b7994
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f9.46c61d22992b7994"
     cluster="k3f9.46c61d22992b7994"
     cluster_size="4"
     filetype = "MS-DOS executable"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre blhw kryptik"
     md5_hashes="['a261db95f4604095808696477181f80c','b246cb4adcee9f14270c071e7a537920','e9a2df3e5168ced48000a324acea8228']"

   strings:
      $hex_string = { 4cdbcbae6f0846593cf0787c2ece9f332adf91865bcd9e96329bf50ef8a475da181a60e12926b6059964d187b2b23a4a3b7ac0c6fbd0f7761cb8a23082af650a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
