import "hash"

rule n3e9_53d216e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.53d216e9c8800b12"
     cluster="n3e9.53d216e9c8800b12"
     cluster_size="63 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="urelas graftor gupboot"
     md5_hashes="['8f28f57d7fea4e158af1dbf9204ae0e1', 'cd72fa26b386ee9e1f9524d3ea9da7c7', '70283f0a633fb1635f1b6dbaa9987c35']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(342688,1024) == "92c36ad682dbc31fc427dee4cda24d54"
}

