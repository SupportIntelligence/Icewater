import "hash"

rule k3e9_53e35226c9839132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.53e35226c9839132"
     cluster="k3e9.53e35226c9839132"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['7d2b65eb7179e21108ac5aa0d42a3faf', '7d2b65eb7179e21108ac5aa0d42a3faf', '7d2b65eb7179e21108ac5aa0d42a3faf']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(7168,1024) == "141652077d77edc442f38376c794f858"
}

