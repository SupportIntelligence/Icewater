import "hash"

rule k3e9_53d2151fa6220216
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.53d2151fa6220216"
     cluster="k3e9.53d2151fa6220216"
     cluster_size="2014 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zbot supatre upatre"
     md5_hashes="['a448c63bcd6815955981c792cd4014f4', '45824225ba1456e8db388e6163fd001c', 'a7d488020d0a0d331057017967706efc']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1024,1024) == "e334cf7360ec06be246d4f1741ec0326"
}

