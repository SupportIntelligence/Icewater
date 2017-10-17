import "hash"

rule n3e9_49b24b56d6c31912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.49b24b56d6c31912"
     cluster="n3e9.49b24b56d6c31912"
     cluster_size="67 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="jacard malicious yantai"
     md5_hashes="['9893a9684ec393d003f6b38ceda39bc7', '2de19d2ced50a377c54f74b927168586', '9b010c22ae0a15450240a63263e4b0ae']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(380928,1024) == "83d93c784e673401d0986926482a032f"
}

