
rule n2319_09316485c6220912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.09316485c6220912"
     cluster="n2319.09316485c6220912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script injector"
     md5_hashes="['e2fa20d4575b498eec04336f6d87cd9badf4f6b8','270fbda9ae4d3f9b4b0d7d9e391b421873404cf3','a1e819673b6a8eae54644f9d532022b144066859']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.09316485c6220912"

   strings:
      $hex_string = { 746368282f5c642b2f67293b662e506c7567696e732e466c6173683d7b76657273696f6e3a4e756d62657228635b305d7c7c22302e222b635b315d297c7c302c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
