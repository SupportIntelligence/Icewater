
rule m3e9_39a5309d06220132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.39a5309d06220132"
     cluster="m3e9.39a5309d06220132"
     cluster_size="36664"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre trojandownloader malicious"
     md5_hashes="['0002814ebf858eca4c60b26b27bdde40','0003b91baadfbce420f41f6166773957','002b74d265ad110718daa42f8c731a92']"

   strings:
      $hex_string = { b235285caa493382417b77b6ecc88138b51741341dbdf2529a7f3a68acd45f894206e01202867515879ee503cfa75065d885e7e1259120cadc6b13e237ef26a8 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
