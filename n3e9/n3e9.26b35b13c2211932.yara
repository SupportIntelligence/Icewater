
rule n3e9_26b35b13c2211932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.26b35b13c2211932"
     cluster="n3e9.26b35b13c2211932"
     cluster_size="1987"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="imali crossrider genericr"
     md5_hashes="['0000dc73b560ac003fc26261ef7b4ce0','002c5fed3d7e0fc882bc087ed6badace','01c49d8f6d2839d4f2fd7a7f47810744']"

   strings:
      $hex_string = { 0f7ce3fefbef179ffffce7f9ce77bea3ebf57a436b6d2a7d15b96ad5aa2163cc40bbdd96499a48a333f24aa954c2f33c849028a5c89585705d3753b6019435b8 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
