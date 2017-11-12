
rule k3e9_499dbc0be6200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.499dbc0be6200b12"
     cluster="k3e9.499dbc0be6200b12"
     cluster_size="201"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="lolbot backdoor zusy"
     md5_hashes="['00de381f5db9b236cb87a08a662bcb00','0209e3576ecbf2f933487c0732566af2','2ed9b837ce5ecf8260186f2679b929a0']"

   strings:
      $hex_string = { 4c4e3036353330005c524c4e3036353237005c524c5436393930005c524c5436393839005c524c5436393838005c524c54363938370044746c67656141656c56 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
