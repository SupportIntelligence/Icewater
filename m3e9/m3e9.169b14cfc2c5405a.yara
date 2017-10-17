import "hash"

rule m3e9_169b14cfc2c5405a
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.169b14cfc2c5405a"
     cluster="m3e9.169b14cfc2c5405a"
     cluster_size="8 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['620ee270f3b9ac341235d49edbdcdc3e', '620ee270f3b9ac341235d49edbdcdc3e', '620ee270f3b9ac341235d49edbdcdc3e']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(208896,1024) == "3900df26de246ca3f457158639d3bd4f"
}

