
rule k2321_2914ad4d989b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2914ad4d989b0b12"
     cluster="k2321.2914ad4d989b0b12"
     cluster_size="12"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba vbkrypt emotet"
     md5_hashes="['2cf70df1f7c74bea9ad6bfda85677bb8','32dea73ef4a8b3a67e7441ba3150293f','ffa355ce0d15b0a6697123f2cd329075']"

   strings:
      $hex_string = { 96453a0b48b940dd508a1c07e7455453d4172bea0a11f465b5f90492ca19e2aae9a2869942f30cfef9c91c34622ff6664c4f90748b08828132a9141d9d80d336 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
